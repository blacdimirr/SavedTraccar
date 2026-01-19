import { useMemo, useState } from 'react';
import {
  Table, TableRow, TableCell, TableHead, TableBody,
} from '@mui/material';
import ChildCareIcon from '@mui/icons-material/ChildCare';
import { useTranslation } from '../common/components/LocalizationProvider';
import PageLayout from '../common/components/PageLayout';
import SettingsMenu from '../settings/components/SettingsMenu';
import CollectionFab from '../settings/components/CollectionFab';
import CollectionActions from '../settings/components/CollectionActions';
import TableShimmer from '../common/components/TableShimmer';
import SearchHeader, { filterByKeyword } from '../settings/components/SearchHeader';
import useSettingsStyles from '../settings/common/useSettingsStyles';
import { useEffectAsync } from '../reactHelper';
import fetchOrThrow from '../common/util/fetchOrThrow';

const ChildrenPage = () => {
  const { classes } = useSettingsStyles();
  const t = useTranslation();

  const [timestamp, setTimestamp] = useState(Date.now());
  const [items, setItems] = useState([]);
  const [devices, setDevices] = useState({});
  const [searchKeyword, setSearchKeyword] = useState('');
  const [loading, setLoading] = useState(false);

  useEffectAsync(async () => {
    const response = await fetchOrThrow('/api/devices');
    const payload = await response.json();
    setDevices(Object.fromEntries(payload.map((device) => [device.id, device])));
  }, []);

  useEffectAsync(async () => {
    setLoading(true);
    try {
      const response = await fetchOrThrow('/api/savekid/children');
      setItems(await response.json());
    } finally {
      setLoading(false);
    }
  }, [timestamp]);

  const calculateAge = useMemo(() => (birthDate) => {
    if (!birthDate) {
      return '';
    }
    const birth = new Date(birthDate);
    if (Number.isNaN(birth.getTime())) {
      return '';
    }
    const today = new Date();
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age -= 1;
    }
    return age >= 0 ? age : '';
  }, []);

  return (
    <PageLayout menu={<SettingsMenu />} breadcrumbs={['savekidModule', 'savekidChildrenTitle']}>
      <SearchHeader keyword={searchKeyword} setKeyword={setSearchKeyword} />
      <Table className={classes.table}>
        <TableHead>
          <TableRow>
            <TableCell>{t('sharedName')}</TableCell>
            <TableCell>{t('savekidLastName')}</TableCell>
            <TableCell>{t('savekidAge')}</TableCell>
            <TableCell>{t('savekidDevice')}</TableCell>
            <TableCell className={classes.columnAction} />
          </TableRow>
        </TableHead>
        <TableBody>
          {!loading ? items.filter(filterByKeyword(searchKeyword)).map((item) => (
            <TableRow key={item.id}>
              <TableCell>{item.name}</TableCell>
              <TableCell>{item.lastName}</TableCell>
              <TableCell>{calculateAge(item.birthDate)}</TableCell>
              <TableCell>{item.deviceId ? devices[item.deviceId]?.name : ''}</TableCell>
              <TableCell className={classes.columnAction} padding="none">
                <CollectionActions
                  itemId={item.id}
                  editPath="/settings/savekid/child"
                  endpoint="savekid/children"
                  setTimestamp={setTimestamp}
                />
              </TableCell>
            </TableRow>
          )) : (<TableShimmer columns={5} endAction />)}
        </TableBody>
      </Table>
      <CollectionFab editPath="/settings/savekid/child" icon={<ChildCareIcon />} />
    </PageLayout>
  );
};

export default ChildrenPage;

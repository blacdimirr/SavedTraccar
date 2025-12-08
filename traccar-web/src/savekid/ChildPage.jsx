import { useState } from 'react';
import TextField from '@mui/material/TextField';
import {
  Accordion, AccordionSummary, AccordionDetails, Typography,
} from '@mui/material';
import ChildCareIcon from '@mui/icons-material/ChildCare';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import EditItemView from '../settings/components/EditItemView';
import { useTranslation } from '../common/components/LocalizationProvider';
import SettingsMenu from '../settings/components/SettingsMenu';
import useSettingsStyles from '../settings/common/useSettingsStyles';
import SelectField from '../common/components/SelectField';

const ChildPage = () => {
  const { classes } = useSettingsStyles();
  const t = useTranslation();

  const [item, setItem] = useState();

  const validate = () => item && item.name && item.lastName && item.deviceId;

  return (
    <EditItemView
      endpoint="savekid/children"
      item={item}
      setItem={setItem}
      validate={validate}
      menu={<SettingsMenu />}
      breadcrumbs={['savekidModule', 'savekidChild']}
      titleIcon={<ChildCareIcon />}
    >
      {item && (
        <>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1">
                {t('savekidBio')}
              </Typography>
            </AccordionSummary>
            <AccordionDetails className={classes.details}>
              <TextField
                value={item.name || ''}
                onChange={(event) => setItem({ ...item, name: event.target.value })}
                label={t('sharedName')}
              />
              <TextField
                value={item.lastName || ''}
                onChange={(event) => setItem({ ...item, lastName: event.target.value })}
                label={t('savekidLastName')}
              />
              <TextField
                label={t('savekidBirthDate')}
                type="date"
                value={item.birthDate ? item.birthDate.split('T')[0] : ''}
                onChange={(event) => setItem({
                  ...item,
                  birthDate: event.target.value ? new Date(event.target.value).toISOString() : null,
                })}
                InputLabelProps={{ shrink: true }}
              />
              <TextField
                type="number"
                inputProps={{ step: 0.1 }}
                label={t('savekidHeight')}
                value={item.height ?? ''}
                onChange={(event) => setItem({ ...item, height: event.target.value ? Number(event.target.value) : null })}
              />
              <TextField
                type="number"
                inputProps={{ step: 0.1 }}
                label={t('savekidWeight')}
                value={item.weight ?? ''}
                onChange={(event) => setItem({ ...item, weight: event.target.value ? Number(event.target.value) : null })}
              />
              <TextField
                multiline
                minRows={2}
                label={t('savekidConditions')}
                value={item.conditions || ''}
                onChange={(event) => setItem({ ...item, conditions: event.target.value })}
              />
              <SelectField
                value={item.deviceId || ''}
                onChange={(event) => setItem({ ...item, deviceId: Number(event.target.value) })}
                endpoint="/api/devices"
                label={t('savekidDevice')}
              />
            </AccordionDetails>
          </Accordion>
        </>
      )}
    </EditItemView>
  );
};

export default ChildPage;
